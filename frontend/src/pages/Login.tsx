/** 登录页：管理员账号密码登录；默认密码首次登录时强制修改。 */
import { useState } from 'react';
import type { AxiosError } from 'axios';
import { Button, Card, Form, Input, Typography } from 'antd';
import { LockOutlined, SafetyCertificateOutlined, UserOutlined } from '@ant-design/icons';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { changePassword, login } from '../api/endpoints';
import { saveToken } from '../api/client';

/** 与后端保持一致的密码长度约束，避免前后端规则漂移 */
const MIN_PASSWORD_LENGTH = 8;

interface LoginFormValues {
  username: string;
  password: string;
}

interface ChangeFormValues {
  oldPassword: string;
  newPassword: string;
  confirmPassword: string;
}

/** 从 axios 错误中提取后端 detail 文案。 */
function extractError(error: unknown): string {
  const axiosError = error as AxiosError<{ detail?: unknown }>;
  const detail = axiosError.response?.data?.detail;
  return typeof detail === 'string' && detail ? detail : '登录失败，请稍后重试';
}

/** 渲染登录卡片与首次登录改密表单。 */
export default function Login() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const redirectTarget = searchParams.get('redirect') || '/';

  const [loading, setLoading] = useState(false);
  const [changing, setChanging] = useState(false);
  const [loginError, setLoginError] = useState('');
  // 首次登录强制改密时保存刚登录成功的凭证上下文
  const [session, setSession] = useState<{ username: string; password: string } | null>(null);
  const [loginForm] = Form.useForm<LoginFormValues>();
  const [changeForm] = Form.useForm<ChangeFormValues>();

  /** 登录成功后的统一跳转。 */
  const enterApp = () => {
    const target = redirectTarget.startsWith('/login') ? '/' : redirectTarget;
    navigate(target, { replace: true });
  };

  /** 提交登录表单。 */
  const handleLogin = async (values: LoginFormValues) => {
    setLoginError('');
    setLoading(true);
    try {
      const result = await login({
        username: values.username.trim(),
        password: values.password,
      });
      saveToken(result.access_token);
      if (result.must_change_password) {
        setSession({ username: result.username, password: values.password });
      } else {
        enterApp();
      }
    } catch (error) {
      setLoginError(extractError(error));
    } finally {
      setLoading(false);
    }
  };

  /** 首次登录场景下提交新密码。 */
  const handleChangePassword = async (values: ChangeFormValues) => {
    setChanging(true);
    try {
      await changePassword({
        old_password: values.oldPassword,
        new_password: values.newPassword,
      });
      enterApp();
    } catch {
      // 错误提示由 axios 拦截器统一处理
    } finally {
      setChanging(false);
    }
  };

  return (
    <div className="login-page">
      <Card className="login-card" bordered={false}>
        <div className="login-brand">
          <SafetyCertificateOutlined className="login-brand__icon" />
          <div>
            <div className="login-brand__title">Mini SIEM</div>
            <div className="login-brand__subtitle">威胁检测平台 · 管理后台</div>
          </div>
        </div>

        {session ? (
          <>
            <Typography.Paragraph type="warning" style={{ marginBottom: 16 }}>
              检测到当前为默认密码，为保证安全请先修改密码后再进入系统。
            </Typography.Paragraph>
            <Form
              form={changeForm}
              layout="vertical"
              initialValues={{ oldPassword: session.password }}
              onFinish={handleChangePassword}
            >
              <Form.Item
                name="oldPassword"
                label="原密码"
                rules={[{ required: true, message: '请输入原密码' }]}
              >
                <Input.Password prefix={<LockOutlined />} placeholder="原密码" autoComplete="current-password" />
              </Form.Item>
              <Form.Item
                name="newPassword"
                label="新密码"
                rules={[
                  { required: true, message: '请输入新密码' },
                  { min: MIN_PASSWORD_LENGTH, message: `新密码至少 ${MIN_PASSWORD_LENGTH} 位` },
                  ({ getFieldValue }) => ({
                    validator(_rule, value) {
                      if (value && /\s/.test(value)) {
                        return Promise.reject(new Error('新密码不能包含空格'));
                      }
                      if (value && getFieldValue('oldPassword') === value) {
                        return Promise.reject(new Error('新密码不能与原密码相同'));
                      }
                      return Promise.resolve();
                    },
                  }),
                ]}
              >
                <Input.Password prefix={<LockOutlined />} placeholder={`至少 ${MIN_PASSWORD_LENGTH} 位`} autoComplete="new-password" />
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
                <Input.Password prefix={<LockOutlined />} placeholder="再次输入新密码" autoComplete="new-password" />
              </Form.Item>
              <Button type="primary" htmlType="submit" block loading={changing}>
                修改密码并进入系统
              </Button>
            </Form>
          </>
        ) : (
          <Form
            form={loginForm}
            layout="vertical"
            initialValues={{ username: 'admin' }}
            onFinish={handleLogin}
          >
            <Form.Item
              name="username"
              label="账号"
              rules={[{ required: true, message: '请输入管理员账号' }]}
            >
              <Input prefix={<UserOutlined />} placeholder="管理员账号" size="large" autoComplete="username" />
            </Form.Item>
            <Form.Item
              name="password"
              label="密码"
              rules={[{ required: true, message: '请输入密码' }]}
              validateStatus={loginError ? 'error' : undefined}
              help={loginError || undefined}
            >
              <Input.Password
                prefix={<LockOutlined />}
                placeholder="密码"
                size="large"
                autoComplete="current-password"
              />
            </Form.Item>
            <Button type="primary" htmlType="submit" block size="large" loading={loading}>
              登录
            </Button>
            <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 12, marginBottom: 0 }}>
              初始账号 admin，初始密码 admin123（首次登录需修改）；忘记密码可在服务器执行
              <Typography.Text code>python reset_admin.py</Typography.Text> 重置。
            </Typography.Paragraph>
          </Form>
        )}
      </Card>
    </div>
  );
}
