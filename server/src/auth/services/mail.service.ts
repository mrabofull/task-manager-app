import { Injectable } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface MailRecord {
  id: string;
  to: string;
  subject: string;
  body: string;
  sentAt: Date;
}

@Injectable()
export class MailService {
  private readonly mailboxPath = path.join(process.cwd(), 'mail-outbox.json');

  async sendVerificationEmail(email: string, code: string): Promise<void> {
    const mail: MailRecord = {
      id: Date.now().toString(),
      to: email,
      subject: 'Email Verification Code',
      body: `Your verification code is: ${code}\n\nThis code will expire in 15 minutes.`,
      sentAt: new Date(),
    };

    await this.saveToOutbox(mail);
  }

  private async saveToOutbox(mail: MailRecord): Promise<void> {
    let mailbox: MailRecord[] = [];

    try {
      const data = await fs.readFile(this.mailboxPath, 'utf-8');
      mailbox = JSON.parse(data);
    } catch (error) {
      // File doesn't exist yet
    }
    mailbox.unshift(mail);

    if (mailbox.length > 10) {
      mailbox = mailbox.slice(0, 10);
    }
    await fs.writeFile(this.mailboxPath, JSON.stringify(mailbox, null, 2));
  }

  async getOutbox(): Promise<MailRecord[]> {
    try {
      const data = await fs.readFile(this.mailboxPath, 'utf-8');
      return JSON.parse(data);
    } catch (error) {
      return [];
    }
  }
}
