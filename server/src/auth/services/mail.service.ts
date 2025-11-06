import { Injectable } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as nodemailer from 'nodemailer';

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
  private transporter: nodemailer.Transporter | null = null;

  constructor() {
    if (process.env.NODE_ENV === 'production' && process.env.SMTP_HOST) {
      this.transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: false, // true for 465, false for other ports
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD,
        },
        // tls: {
        //   rejectUnauthorized: false,
        // },
      });
    }
  }

  async sendVerificationEmail(email: string, code: string): Promise<void> {
    const subject = 'Email Verification Code - Task Manager';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Email Verification</h2>
        <p>Your verification code is:</p>
        <div style="background: #f0f0f0; padding: 20px; text-align: center; margin: 20px 0;">
          <h1 style="font-size: 36px; letter-spacing: 8px; color: #4F46E5; margin: 0;">${code}</h1>
        </div>
        <p>This code will expire in 15 minutes.</p>
        <p style="color: #666; font-size: 14px;">If you didn't request this, please ignore this email.</p>
      </div>
    `;

    if (process.env.NODE_ENV === 'production' && this.transporter) {
      // Production: Send real email
      await this.transporter.sendMail({
        from: `"${process.env.SMTP_FROM_NAME || 'Task Manager'}" <${process.env.SMTP_USER}>`,
        to: email,
        subject,
        html,
      });
    } else {
      // Development: Save to mailbox file
      const mail: MailRecord = {
        id: Date.now().toString(),
        to: email,
        subject,
        body: `Your verification code is: ${code}\n\nThis code will expire in 15 minutes.`,
        sentAt: new Date(),
      };
      await this.saveToOutbox(mail);
    }
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
