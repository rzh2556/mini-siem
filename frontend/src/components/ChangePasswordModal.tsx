/** 修改密码弹窗：登录后用户自助修改当前账号密码。 */
import { useState } from 'react';
import { Form, Input, Modal, message } from 'antd';
import { changePassword } from '../api/endpoints';

/** 与后端保持一致的密码长度约束 */
const MIN_PASSWORD_LENGTH = 8;

interface ChangePasswordModalProps {
  open: boolean;
  onClose: () => void;
}

interface FormValues {
  oldPassword: string;
  newPassword: string;
  confirmPassword: string;
}

/** 渲染修改密码表单弹窗。 */
export default function ChangePasswordModal({ open, onClose }: ChangePasswordModalProps) {
  const [form] = Form.useForm<FormValues>();
  const [submitting, setSubmitting] = useState(false);

  /** 提交修改：成功后关闭弹窗并清空表单。 */
  const handleOk = async () => {
    const values = await form.validateFields();
    setSubmitting(true);
    try {
      await changePassword({
        old_password: values.oldPassword,
        new_password: values.newPassword,
      });
      message.success('密码修改成功，下次登录请使用新密码');
      form.resetFields();
      onClose();
    } catch (error) {
      if (error && typeof error === 'object' && 'errorFields' in error) {
        // 表单校验失败，不提示全局错误
        return;
      }
      // 其他错误由 axios 拦截器统一提示
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      title="修改登录密码"
      open={open}
      onOk={handleOk}
      onCancel={onClose}
      confirmLoading={submitting}
      okText="确认修改"
      cancelText="取消"
      destroyOnClose
      afterOpenChange={(visible) => {
        if (!visible) {
          form.resetFields();
        }
      }}
    >
      <Form form={form} layout="vertical" style={{ marginTop: 12 }}>
        <Form.Item
          name="oldPassword"
          label="原密码"
          rules={[{ required: true, message: '请输入原密码' }]}
        >
          <Input.Password placeholder="当前密码" autoComplete="current-password" />
        </Form.Item>
        <Form.Item
          name="newPassword"
          label="新密码"
          rules={[
            { required: true, message: '请输入新密码' },
            { min: MIN_PASSWORD_LENGTH, message: `新密码至少 ${MIN_PASSWORD_LENGTH} 位` },
            ({ getFieldValue }) => ({
              validator(_rule, value) {
                if (!value) {
                  return Promise.resolve();
                }
                if (/\s/.test(value)) {
                  return Promise.reject(new Error('新密码不能包含空格'));
                }
                if (getFieldValue('oldPassword') === value) {
                  return Promise.reject(new Error('新密码不能与原密码相同'));
                }
                return Promise.resolve();
              },
            }),
          ]}
        >
          <Input.Password placeholder={`至少 ${MIN_PASSWORD_LENGTH} 位`} autoComplete="new-password" />
        </Form.Item>
        <Form.Item
          name="confirmPassword"
          label="确认新密码"
          dependencies={['newPassword']}
          rules={[
            { required: true, message: '请再次输入新密码' },
            ({ getFieldValue }) => ({
              validator(_rule, value) {
                if (!value || getFieldValue('newPassword') === value) {
                  return Promise.resolve();
                }
                return Promise.reject(new Error('两次输入的新密码不一致'));
              },
            }),
          ]}
        >
          <Input.Password placeholder="再次输入新密码" autoComplete="new-password" />
        </Form.Item>
      </Form>
    </Modal>
  );
}
