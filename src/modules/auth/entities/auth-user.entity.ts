import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
} from 'typeorm';

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

  // ✅ 新增：信箱（字串）
  @Column({ unique: true, type: 'varchar', length: 254, nullable: true })
  email: string | null;

  // ✅ 新增：手機（字串）
  @Column({ unique: true, type: 'varchar', length: 20, nullable: true })
  mobile: string | null;

  @Column({ type: 'varchar', length: 4, default: '1' })
  vipLevel: string;

  @Column({ type: 'varchar', length: 3, default: '0', nullable: true })
  vipProgress: string | null;

  @CreateDateColumn()
  createdAt: Date;
}
