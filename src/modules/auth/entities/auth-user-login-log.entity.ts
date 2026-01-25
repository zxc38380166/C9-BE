import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { AuthUser } from './auth-user.entity';
import ENUMS from 'src/enum';

@Entity('auth-user-login-log')
@Index(['userId', 'lastUse'])
export class AuthUserLoginLog {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'int' })
  userId: number;

  @ManyToOne(() => AuthUser, (user) => user.loginLogs, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId', referencedColumnName: 'id' }) // 指定關聯母表欄位
  user: AuthUser;

  @Column({ type: 'varchar', length: 255 })
  device: string;

  @Column({ type: 'varchar', length: 45 })
  ip: string;

  @Column({ type: 'datetime' })
  lastUse: Date;

  @Column({ type: 'varchar', length: 30 })
  action: keyof typeof ENUMS.AUTH_ENUM.LOGIN_LOG.ACTION;

  @CreateDateColumn({ type: 'datetime' })
  createdAt: Date;
}
