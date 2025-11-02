import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity('login_attempts')
export class LoginAttempt {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: true })
  email?: string;

  @Column()
  ipAddress: string;

  @Column({ type: 'int', default: 1 })
  attemptCount: number;

  @Column({ type: 'timestamp', nullable: true })
  lockoutUntil?: Date;

  @CreateDateColumn()
  createdAt: Date;
}
