import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
  } from 'typeorm';
  
  @Entity('users')
  export class AuthUser {
    @PrimaryGeneratedColumn()
    id: number;
  
    @Column({ unique: true })
    account: string;
  
    @Column()
    password: string;
  
    @Column()
    name: string;
  
    @CreateDateColumn()
    createdAt: Date;
  }
  