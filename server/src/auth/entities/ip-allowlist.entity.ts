import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('ip_allowlist')
export class IpAllowlist {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  ip: string;

  @Column({ nullable: true })
  label?: string;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
