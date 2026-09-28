/** Sigma 规则导入弹窗：上传/粘贴 Sigma YAML，转换为内部规则并展示逐条导入结果。 */
import { useState } from 'react';
import {
  Alert,
  Button,
  Descriptions,
  Modal,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  Upload,
  message,
} from 'antd';
import { ImportOutlined, UploadOutlined } from '@ant-design/icons';
import type { UploadFile } from 'antd/es/upload/interface';
import type { ColumnsType } from 'antd/es/table';
import { importSigmaRules } from '../api/endpoints';
import type { SigmaImportItem, SigmaImportResponse } from '../api/types';

interface SigmaImportModalProps {
  open: boolean;
  onClose: () => void;
  /** 导入成功后回调（用于刷新规则列表） */
  onImported: () => void;
}

/** 单条结果状态对应的标签颜色与文案 */
const STATUS_META: Record<SigmaImportItem['status'], { color: string; text: string }> = {
  imported: { color: 'success', text: '已导入' },
  skipped: { color: 'warning', text: '已跳过' },
  error: { color: 'error', text: '失败' },
};

/** 渲染 Sigma 规则导入弹窗。 */
export default function SigmaImportModal({ open, onClose, onImported }: SigmaImportModalProps) {
  const [content, setContent] = useState('');
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [overwrite, setOverwrite] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<SigmaImportResponse | null>(null);

  /** 关闭并重置全部状态。 */
  const handleClose = () => {
    setContent('');
    setFileList([]);
    setOverwrite(false);
    setResult(null);
    onClose();
  };

  /** 读取选中的 .yml/.yaml 文件文本并填充到粘贴框。 */
  const readFile = (file: File) => {
    const reader = new FileReader();
    reader.onload = () => {
      setContent(String(reader.result ?? ''));
      setResult(null);
    };
    reader.onerror = () => message.error('文件读取失败');
    reader.readAsText(file, 'utf-8');
  };

  /** 提交导入并展示逐条结果。 */
  const handleImport = () => {
    if (!content.trim()) {
      message.warning('请先选择 Sigma YAML 文件或粘贴规则内容');
      return;
    }
    setSubmitting(true);
    importSigmaRules(content, overwrite)
      .then((data) => {
        setResult(data);
        if (data.imported > 0) {
          message.success(`成功导入 ${data.imported} 条规则`);
          onImported();
        } else {
          message.warning('没有可导入的规则，请查看逐条结果');
        }
      })
      .catch(() => undefined) // 错误提示由 axios 拦截器统一处理
      .finally(() => setSubmitting(false));
  };

  /** 结果表格列定义。 */
  const columns: ColumnsType<SigmaImportItem> = [
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (status: SigmaImportItem['status']) => (
        <Tag color={STATUS_META[status].color}>{STATUS_META[status].text}</Tag>
      ),
    },
    {
      title: '规则标题',
      dataIndex: 'title',
      key: 'title',
      width: 220,
      render: (title: string) => <Typography.Text strong>{title}</Typography.Text>,
    },
    {
      title: '生成的内部规则 ID',
      dataIndex: 'rule_ids',
      key: 'rule_ids',
      render: (ids?: string[] | null) =>
        ids && ids.length > 0 ? (
          <Space size={4} wrap>
            {ids.map((id) => (
              <Tag key={id} color="blue">
                {id}
              </Tag>
            ))}
          </Space>
        ) : (
          '-'
        ),
    },
    {
      title: '说明 / 警告 / 错误',
      key: 'detail',
      render: (_v, record) => (
        <Space direction="vertical" size={2} style={{ width: '100%' }}>
          {record.error ? (
            <Typography.Text type="danger" style={{ fontSize: 12 }}>
              {record.error}
            </Typography.Text>
          ) : null}
          {(record.warnings ?? []).map((warning) => (
            <Typography.Text key={warning} type="warning" style={{ fontSize: 12 }}>
              ⚠ {warning}
            </Typography.Text>
          ))}
        </Space>
      ),
    },
  ];

  return (
    <Modal
      title="导入 Sigma 规则（YAML）"
      open={open}
      width={900}
      onCancel={handleClose}
      maskClosable={false}
      destroyOnClose
      footer={
        <Space>
          <Button onClick={handleClose}>关闭</Button>
          <Button
            type="primary"
            icon={<ImportOutlined />}
            loading={submitting}
            onClick={handleImport}
          >
            开始转换并导入
          </Button>
        </Space>
      }
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="支持 Sigma 官方规则的常用子集"
        description="可导入来自 SigmaHQ/规则仓库的 .yml/.yaml 文件（支持一个文件内用 --- 分隔多条）。字段修饰符支持 contains/startswith/endswith/re/base64/base64offset/windash/大小比较；暂不支持 count/near 聚合、cidr、null 等（对应规则会逐条报错，不会静默忽略）。OR 条件会自动拆分为多条内部规则。"
      />

      <Upload
        accept=".yml,.yaml"
        maxCount={1}
        fileList={fileList}
        beforeUpload={(file) => {
          setFileList([file]);
          readFile(file);
          return false; // 阻止 antd 自动上传，仅读取文本
        }}
        onRemove={() => {
          setFileList([]);
          setContent('');
          return true;
        }}
      >
        <Button icon={<UploadOutlined />}>选择 Sigma YAML 文件</Button>
      </Upload>

      <Typography.Paragraph type="secondary" style={{ fontSize: 12, margin: '8px 0 4px' }}>
        也可以直接把 Sigma YAML 内容粘贴到下方（文件与粘贴框内容一致，任选其一）：
      </Typography.Paragraph>
      <Typography.Paragraph>
        <textarea
          value={content}
          onChange={(event) => {
            setContent(event.target.value);
            setResult(null);
          }}
          placeholder={'title: 示例规则\nid: 00000000-0000-0000-0000-000000000000\nlogsource:\n  product: windows\ndetection:\n  selection:\n    EventID: 4625\n  condition: selection\nlevel: high'}
          style={{
            width: '100%',
            minHeight: 180,
            fontFamily: 'monospace',
            fontSize: 12,
            padding: 8,
            borderRadius: 6,
            border: '1px solid #434343',
            background: '#1f1f1f',
            color: 'rgba(255,255,255,0.85)',
            resize: 'vertical',
          }}
        />
      </Typography.Paragraph>

      <Space style={{ marginBottom: 12 }}>
        <Switch checked={overwrite} onChange={setOverwrite} />
        <Typography.Text>覆盖已存在的同 ID 自定义规则（内置规则始终不可覆盖）</Typography.Text>
      </Space>

      {result ? (
        <>
          <Descriptions size="small" column={3} bordered style={{ marginBottom: 12 }}>
            <Descriptions.Item label="成功导入">{result.imported}</Descriptions.Item>
            <Descriptions.Item label="跳过">{result.skipped}</Descriptions.Item>
            <Descriptions.Item label="失败">{result.failed}</Descriptions.Item>
          </Descriptions>
          <Table<SigmaImportItem>
            rowKey={(_record, index) => String(index)}
            size="small"
            columns={columns}
            dataSource={result.items}
            pagination={false}
            scroll={{ y: 260 }}
          />
        </>
      ) : null}
    </Modal>
  );
}
