// game-type.enum.ts
export enum GAME_TYPE {
  SLOTS = 1,
  LIVE = 2,
  CHESS = 3,
  FISH = 4,
  SPORT = 5,
  CRYPTO = 6,
  ESPORT = 7,
}

// 如果你也想要「代碼 -> 字串 key」對照（'slots' / 'live'...）
export enum GAME_TYPE_KEY {
  SLOTS = 'slots',
  LIVE = 'live',
  CHESS = 'chess',
  FISH = 'fish',
  SPORT = 'sport',
  CRYPTO = 'crypto',
  ESPORT = 'esport',
}

// 常用：數字 enum 轉 key（強型別）
export const GAME_TYPE_TO_KEY: Record<GAME_TYPE, GAME_TYPE_KEY> = {
  [GAME_TYPE.SLOTS]: GAME_TYPE_KEY.SLOTS,
  [GAME_TYPE.LIVE]: GAME_TYPE_KEY.LIVE,
  [GAME_TYPE.CHESS]: GAME_TYPE_KEY.CHESS,
  [GAME_TYPE.FISH]: GAME_TYPE_KEY.FISH,
  [GAME_TYPE.SPORT]: GAME_TYPE_KEY.SPORT,
  [GAME_TYPE.CRYPTO]: GAME_TYPE_KEY.CRYPTO,
  [GAME_TYPE.ESPORT]: GAME_TYPE_KEY.ESPORT,
};
