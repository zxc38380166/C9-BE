import { Controller, Get, Query } from '@nestjs/common';
import { GameService } from './game.service';

@Controller('game')
export class GameController {
  constructor(private readonly gameService: GameService) {}

  @Get('/provider')
  async getGameProvider(@Query() query: string) {
    return await this.gameService.getGameProvider(query);
  }
}
