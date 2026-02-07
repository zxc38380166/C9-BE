import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
} from 'typeorm';

@Entity('game-provider')
export class GameProvider {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  gameCode: string;

  @Column({ type: 'int' })
  gameType: number;

  @Column({ type: 'tinyint', width: 1, default: 0 })
  areaBlock: boolean;

  @Column({ type: 'tinyint', width: 1, default: 0 })
  maintain: boolean;

  @Column({ type: 'tinyint', width: 1, default: 1 })
  enable: boolean;

  @CreateDateColumn()
  createdAt: Date;
}
