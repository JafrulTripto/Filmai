import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto, UserDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {


    constructor( private authService: AuthService) {
        
    }

    @Post('signup')
    signup(@Body() body: UserDto): Promise<Tokens> {
        return this.authService.signup(body);
    }

    @Post('login')
    login(@Body() body: AuthDto): Promise<Tokens> {
        return this.authService.login(body);
    }

    @Post('logout')
    logout() {
        this.authService.logout();
    }

    @Post('refresh')
    refreshTokens() {
        this.authService.refreshTokens();
    }
}
