import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { CatsController } from './cats/cats.controller';
import { CatsService } from './cats/cats.service';
import { AuthMiddleware } from './auth.middleware';

@Module({
  imports: [TypeOrmModule.forRoot({ type: 'postgres' })],
  controllers: [CatsController],
  providers: [CatsService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(AuthMiddleware).forRoutes({ path: 'cats', method: RequestMethod.POST });
  }
}
