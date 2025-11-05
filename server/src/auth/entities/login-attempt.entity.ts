import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('login_attempts')
export class LoginAttempt {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: true })
  email?: string;

  @Column()
  ipAddress: string;

  @Column({ type: 'int', default: 0 })
  attemptCount: number;

  @Column({ type: 'timestamp', nullable: true })
  lockoutUntil?: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  lastAttemptAt?: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
