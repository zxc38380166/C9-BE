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

@Module({
  imports: [
    TypeOrmModule.forFeature([AuthUser]),
    // env
    ConfigModule.forRoot({
      isGlobal: true,
    }),

    // MySQL
    TypeOrmModule.forRootAsync({
      useFactory: typeOrmConfig,
    }),

    JwtModule.register({
      secret: process.env.JWT_SECRET || 'c9-secret',
      signOptions: { expiresIn: '7d' },
    }),

    // modules
    AuthModule,

    GameModule,

    CommonModule,
  ],
  providers: [AuthService, JwtStrategy],
})
export class AppModule {}
