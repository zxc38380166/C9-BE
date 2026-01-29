import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { typeOrmConfig } from '../config/typeorm.config';
import { AuthModule } from './modules/auth/auth.module';
import { AuthService } from './modules/auth/auth.service';
import { JwtStrategy } from './modules/auth/strategies/jwt.strategy';
import { AuthUser } from './modules/auth/entities/auth-user.entity';
import { GameModule } from './modules/game/game.module';
import { CommonModule } from './modules/common/common.module';
import { AuthUserLoginLog } from './modules/auth/entities/auth-user-login-log.entity';
import { TimeModule } from './time/time.module';
import * as path from 'path';
import {
  AcceptLanguageResolver,
  HeaderResolver,
  I18nModule,
} from 'nestjs-i18n';

@Module({
  imports: [
    TypeOrmModule.forFeature([AuthUser, AuthUserLoginLog]),
    // env
    ConfigModule.forRoot({ isGlobal: true }),
    // MySQL
    TypeOrmModule.forRootAsync({ useFactory: typeOrmConfig }),
    // JWT
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'c9-secret',
      signOptions: { expiresIn: '7d' },
    }),
    I18nModule.forRoot({
      fallbackLanguage: 'zh-TW',
      loaderOptions: {
        path: path.join(__dirname, '../i18n'),
        watch: process.env.NODE_ENV === 'development',
      },
      resolvers: [
        new HeaderResolver(['locales']),
        new AcceptLanguageResolver(),
      ],
    }),
    AuthModule,
    GameModule,
    CommonModule,
    TimeModule,
  ],
  providers: [AuthService, JwtStrategy],
})
export class AppModule {}
