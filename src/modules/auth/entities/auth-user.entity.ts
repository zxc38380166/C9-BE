import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
} from 'typeorm';
import type { Request as _Request } from 'express';

export interface Request extends _Request {
  user?: AuthUser;
}

@Entity('auth-user')
export class AuthUser {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', length: 50 })
  account: string;

  @Column({ type: 'varchar', length: 255 })
  password: string;

  @Column({ type: 'varchar', length: 50 })
  name: string;

  @Column({ unique: true, type: 'varchar', length: 254, nullable: true })
  email: string | null;

  @Column({ type: 'varchar', length: 6, nullable: true })
  emailVertifyCode: string | null;

  @Column({ unique: true, type: 'varchar', length: 20, nullable: true })
  mobile: string | null;

  @Column({ type: 'varchar', length: 4, default: '1' })
  vipLevel: string;

  @Column({ type: 'varchar', length: 3, default: '0', nullable: true })
  vipProgress: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
