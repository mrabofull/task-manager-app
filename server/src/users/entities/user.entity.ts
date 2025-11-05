import { UserSession } from 'src/auth/entities/user-session.entity';
import { VerificationCode } from 'src/auth/entities/verification-code.entity';
import { Task } from 'src/tasks/entities/task.entity';
import {
  Column,
  CreateDateColumn,
  Entity,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column({ default: '' })
  name: string;

  @Column({ type: 'timestamp', nullable: true })
  emailVerifiedAt?: Date;

  @Column()
  passwordHash: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany(() => Task, (task) => task.user)
  tasks: Task[];

  @OneToMany(() => VerificationCode, (code) => code.user)
  verificationCodes: VerificationCode[];

  @OneToMany(() => UserSession, (session) => session.user)
  sessions: UserSession[];
}
