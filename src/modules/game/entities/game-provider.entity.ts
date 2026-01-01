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

  @Column({ type: 'text' })
  gameKey: string;

  @Column({ type: 'tinyint', width: 1, default: 0 })
  regionalOpen: boolean;

  @Column({ type: 'tinyint', width: 1, default: 1 })
  enable: boolean;

  @CreateDateColumn()
  createdAt: Date;
}
