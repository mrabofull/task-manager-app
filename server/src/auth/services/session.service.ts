import { InjectRepository } from '@nestjs/typeorm';
import { UserSession } from '../entities/user-session.entity';
import { Repository } from 'typeorm';
import { User } from 'src/users/entities/user.entity';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class SessionService {
  private readonly maxSessions: number;

  constructor(
    @InjectRepository(UserSession)
    private sessionRepository: Repository<UserSession>,
    private configService: ConfigService,
  ) {
    this.maxSessions = this.configService.get<number>('MAX_USER_SESSIONS', 3);
  }

  async createSession(
    user: User,
    refreshToken: string,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<UserSession> {
    const sessions = await this.sessionRepository.find({
      where: { user: { id: user.id } },
      order: { lastUsedAt: 'ASC' },
    });

    if (sessions.length >= this.maxSessions) {
      await this.sessionRepository.delete(sessions[0].id);
    }

    const session = this.sessionRepository.create({
      user,
      refreshToken,
      userAgent,
      ipAddress,
      lastUsedAt: new Date(),
    });

    return this.sessionRepository.save(session);
  }

  async findByRefreshToken(refreshToken: string): Promise<UserSession | null> {
    return this.sessionRepository.findOne({
      where: { refreshToken },
      relations: ['user'],
    });
  }

  async updateLastUsed(sessionId: string): Promise<void> {
    await this.sessionRepository.update(sessionId, {
      lastUsedAt: new Date(),
    });
  }

  async deleteSession(refreshToken: string): Promise<void> {
    await this.sessionRepository.delete({ refreshToken });
  }

  async deleteAllUserSessions(userId: string): Promise<void> {
    await this.sessionRepository.delete({ user: { id: userId } });
  }
}
