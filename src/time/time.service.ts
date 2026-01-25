import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import moment from 'moment-timezone';

@Injectable()
export class TimeService {
  readonly TZ: string;

  constructor(private readonly config: ConfigService) {
    this.TZ = this.config.get<string>('TZ') || 'Asia/Seoul';
  }

  /** moment instance in TZ */
  m(input?: moment.MomentInput) {
    return input ? moment(input).tz(this.TZ) : moment().tz(this.TZ);
  }

  /** Date (DB-friendly) */
  nowDate() {
    return this.m().toDate();
  }

  /** ISO-ish string with TZ applied (for display/log/email) */
  nowString(format = moment.HTML5_FMT.DATETIME_LOCAL_SECONDS) {
    return this.m().format(format);
  }

  /** Convert any input to Date using TZ */
  toDate(input: moment.MomentInput) {
    return this.m(input).toDate();
  }
}
