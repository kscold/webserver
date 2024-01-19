import Joi from 'joi';
import User from '../../models/user';

// POST /api/auth/register
// {
//     username: 'velopert',
//     loginid: 'myid123',
//     password: 'mypass123'
// }

export const register = async (ctx) => {
  // 회원가입
  // Request Body 검증
  const schema = Joi.object().keys({
    username: Joi.string().max(10).required(),
    loginid: Joi.string().alphanum().min(3).max(20).required(),
    password: Joi.string().required(),
  });

  const result = schema.validate(ctx.request.body);
  if (result.error) {
    ctx.status = 400;
    ctx.body = result.error;
    return;
  }

  const { username, loginid, password } = ctx.request.body;
  try {
    const exists = await User.findByLoginId(loginid);
    if (exists) {
      ctx.status = 409; // Conflict
      return;
    }

    const user = new User({
      username,
      loginid,
    });

    await user.setPassword(password);
    await user.save();

    ctx.body = user.serialize();

    const token = user.generateToken();
    ctx.cookies.set('access_token', token, {
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7일
      httpOnly: true,
    });
  } catch (e) {
    ctx.throw(500, e);
  }
};

// POST /api/auth/login
// {
//     loginid: 'myid123',
//     password: 'mypass123'
// }

export const login = async (ctx) => {
  // 로그인
  const { loginid, password } = ctx.request.body;

  if (!loginid || !password) {
    ctx.status = 401; // Unauthorized
    return;
  }

  try {
    const user = await User.findByLoginId(loginid);
    if (!user) {
      ctx.status = 401; // conflict
      return;
    }
    const valid = await user.checkPassword(password);
    if (!valid) {
      ctx.status = 401; // conflict
      return;
    }
    ctx.body = user.serialize();
    const token = user.generateToken();
    ctx.cookies.set('access_token', token, {
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7일
      httpOnly: true,
    });
  } catch (e) {
    ctx.throw(500, e);
  }
};

// GET /api/auth/check
export const check = async (ctx) => {
  // 로그인 상태 확인
  const { user } = ctx.state;
  console.log(ctx.state);
  if (!user) {
    // 로그인 중 아님
    ctx.status = 401; // Unauthorized
    return;
  }
  ctx.body = user;
};

export const logout = async (ctx) => {
  // 로그아웃
  ctx.cookies.set('access_token');
  ctx.status = 204;
};
