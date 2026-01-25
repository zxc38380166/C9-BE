export const AUTH_ENUM = {
  RELATED: {
    LOGIN_LOG: 'LOGIN_LOG',
  },
  LOGIN_LOG: {
    ACTION: {
      LOGIN: '登入',
      LOGOUT: '登出',
      DEL: '移除',
      UNCAPTURED: '未補獲',
    },
  },
} as const satisfies {
  RELATED: {
    LOGIN_LOG: 'LOGIN_LOG';
  };
  LOGIN_LOG: {
    ACTION: Record<'LOGIN' | 'LOGOUT' | 'DEL' | 'UNCAPTURED', string>;
  };
};
