import { Module } from '@nestjs/common';
import { GameService } from './game.service';
import { GameController } from './game.controller';
import { GameProvider } from './entities/game-provider.entity';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [TypeOrmModule.forFeature([GameProvider])],
  controllers: [GameController],
  providers: [GameService],
})
export class GameModule {}
