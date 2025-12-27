import { Injectable } from '@nestjs/common';
import enums from 'src/enum';

@Injectable()
export class CommonService {
  async getEnums(query) {
    return enums;
  }
}
