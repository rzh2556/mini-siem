/** 日志上传弹窗：选择单个日志文件提交后端解析，并在同一弹窗内展示解析结果与命中规则预览。 */
import { useState } from 'react';
import {
  Button,
  Descriptions,
  Form,
  Input,
  Modal,
  Progress,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  Upload,
  message,
} from 'antd';
import type { UploadFile } from 'antd/es/upload/interface';
import type { ColumnsType } from 'antd/es/table';
import { uploadLogFile } from '../api/endpoints';
import type { UploadPreviewItem, UploadResult } from '../api/types';
import { formatTime } from '../utils/format';

/** 日志类型可选项，第一项为后端自动识别 */
const SOURCE_TYPE_OPTIONS = [
  { label: '自动识别', value: 'auto' },
  { label: 'Nginx', value: 'nginx' },
  { label: 'Apache', value: 'apache' },
  { label: 'SSH 认证日志', value: 'ssh' },
  { label: 'Linux 系统日志', value: 'linux' },
  { label: 'Windows 事件日志', value: 'windows' },
  { label: '通用 Syslog', value: 'syslog' },
];

/** 上传表单字段 */
interface UploadForm {
  host?: string;
  source_type?: string;
}

/** 上传弹窗属性 */
interface UploadLogModalProps {
  /** 是否可见 */
  open: boolean;
  /** 关闭弹窗回调 */
  onClose: () => void;
  /** 上传解析成功后的回调（用于外部刷新日志列表） */
  onSuccess: () => void;
}

/** 渲染日志上传弹窗。 */
export default function UploadLogModal({ open, onClose, onSuccess }: UploadLogModalProps) {
  const [form] = Form.useForm<UploadForm>();
  const [file, setFile] = useState<File | null>(null);
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [uploading, setUploading] = useState(false);
  const [percent, setPercent] = useState(0);
  const [result, setResult] = useState<UploadResult | null>(null);

  /** 重置表单、待上传文件与解析结果 */
  const resetAll = () => {
    form.resetFields();
    setFile(null);
    setFileList([]);
    setPercent(0);
    setResult(null);
  };

  /** 关闭弹窗并清理内部状态 */
  const handleClose = () => {
    resetAll();
    onClose();
  };

  /** 开始上传：提交文件并根据进度与结果更新界面 */
  const handleUpload = () => {
    if (!file) {
      message.warning('请先选择要上传的日志文件');
      return;
    }
    const values = form.getFieldsValue();
    setUploading(true);
    setPercent(0);
    uploadLogFile(file, values.host ?? '', values.source_type ?? 'auto', setPercent)
      .then((data) => {
        setPercent(100);
        setResult(data);
        message.success(`解析完成：入库 ${data.accepted} 条，新增告警 ${data.alerts} 条`);
        onSuccess();
      })
      .catch(() => undefined) // 错误提示已由 axios 拦截器统一处理
      .finally(() => setUploading(false));
  };

  /** 预览表格列定义 */
  const columns: ColumnsType<UploadPreviewItem> = [
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 170,
      render: (value?: string) => formatTime(value),
    },
    {
      title: '源 IP',
      dataIndex: 'src_ip',
      key: 'src_ip',
      width: 130,
      render: (value?: string | null) => value || '-',
    },
    {
      title: '用户',
      dataIndex: 'user',
      key: 'user',
      width: 100,
      render: (value?: string | null) => value || '-',
    },
    {
      title: '等级',
      dataIndex: 'level',
      key: 'level',
      width: 90,
      render: (value?: string) => value || '-',
    },
    {
      title: '日志摘要',
      dataIndex: 'message',
      key: 'message',
      render: (value?: string) => (
        <Typography.Text style={{ wordBreak: 'break-all' }}>{value || '-'}</Typography.Text>
      ),
    },
    {
      title: '命中规则',
      dataIndex: 'matched',
      key: 'matched',
      width: 200,
      render: (matched?: string[]) =>
        matched && matched.length > 0
          ? matched.map((rule) => (
              <Tag key={rule} color="red">
                {rule}
              </Tag>
            ))
          : '-',
    },
  ];

  /** 渲染底部操作按钮：未出结果时显示上传动作，出结果后显示重置动作 */
  const renderFooter = () => {
    if (result) {
      return (
        <Space>
          <Button onClick={resetAll}>再传一个</Button>
          <Button type="primary" onClick={handleClose}>
            完成
          </Button>
        </Space>
      );
    }
    return (
      <Space>
        <Button onClick={handleClose} disabled={uploading}>
          取消
        </Button>
        <Button type="primary" loading={uploading} disabled={!file} onClick={handleUpload}>
          开始上传
        </Button>
      </Space>
    );
  };

  return (
    <Modal
      title="上传日志文件并解析"
      open={open}
      width={860}
      onCancel={handleClose}
      maskClosable={!uploading}
      footer={renderFooter()}
    >
      {result ? (
        <>
          <Descriptions column={2} size="small" bordered>
            <Descriptions.Item label="文件名" span={2}>
              {result.filename}
            </Descriptions.Item>
            <Descriptions.Item label="识别的日志类型">
              <Tag color="cyan">{result.source_type}</Tag>
              {result.auto_detected ? <span>（自动识别）</span> : null}
            </Descriptions.Item>
            <Descriptions.Item label="新增告警数">
              {result.alerts > 0 ? <Tag color="red">{result.alerts}</Tag> : result.alerts}
            </Descriptions.Item>
            <Descriptions.Item label="总行数">{result.total_lines}</Descriptions.Item>
            <Descriptions.Item label="入库条数">{result.accepted}</Descriptions.Item>
            <Descriptions.Item label="跳过条数" span={2}>
              {result.skipped}
            </Descriptions.Item>
          </Descriptions>

          {result.alerts > 0 ? (
            <Typography.Paragraph style={{ marginTop: 12 }}>
              本次解析产生 {result.alerts} 条新告警，可前往
              <Typography.Link onClick={handleClose}> 告警中心 </Typography.Link>
              查看详情。
            </Typography.Paragraph>
          ) : null}

          <div className="section-label">解析结果预览（前 5 条）</div>
          <Table<UploadPreviewItem>
            rowKey={(_record, index) => String(index)}
            size="small"
            columns={columns}
            dataSource={result.preview}
            pagination={false}
            scroll={{ x: 780 }}
          />
        </>
      ) : (
        <>
          <Typography.Paragraph type="secondary" style={{ marginBottom: 16 }}>
            支持两类文件：① Nginx / Apache / SSH / 通用 Syslog 等文本日志（.log/.txt）；
            ② Windows 事件日志导出文件（.evtx，可直接从“事件查看器”导出后上传，将按 Windows 规则检测）。
            单个文件不超过 50MB。
          </Typography.Paragraph>

          <Form<UploadForm> form={form} layout="vertical" initialValues={{ source_type: 'auto' }}>
            <Form.Item name="host" label="来源主机名">
              <Input allowClear placeholder="如 web-01，留空则由后端使用默认值 upload" />
            </Form.Item>
            <Form.Item name="source_type" label="日志类型">
              <Select options={SOURCE_TYPE_OPTIONS} />
            </Form.Item>
          </Form>

          <Upload.Dragger
            accept=".log,.txt,.log.1,.out,.evtx"
            maxCount={1}
            fileList={fileList}
            beforeUpload={(selected) => {
              setFile(selected);
              setFileList([selected]);
              // EVTX 固定按 Windows 事件处理，自动纠正用户可能选错的日志类型
              if (selected.name.toLowerCase().endsWith('.evtx')) {
                form.setFieldValue('source_type', 'windows');
              }
              return false;
            }}
            onRemove={() => {
              setFile(null);
              setFileList([]);
              return true;
            }}
            disabled={uploading}
          >
            <p className="ant-upload-text">点击或拖拽日志文件到此处</p>
            <p className="ant-upload-hint">支持文本日志与 Windows .evtx 事件文件，最大 50MB</p>
          </Upload.Dragger>

          {uploading ? (
            <Progress style={{ marginTop: 16 }} percent={percent} status="active" />
          ) : null}
        </>
      )}
    </Modal>
  );
}
