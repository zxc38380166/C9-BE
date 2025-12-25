import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { GameProvider } from './entities/game-provider.entity';
import { Repository } from 'typeorm';

@Injectable()
export class GameService {
  constructor(
    @InjectRepository(GameProvider)
    private readonly gameProviderRep: Repository<GameProvider>,
  ) {}

  async getGameProvider(query) {
    console.log(query, 'query');

    return await this.gameProviderRep.find();
  }
}
