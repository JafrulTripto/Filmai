import { Body, Controller, HttpCode, HttpStatus, Post, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { AuthDto, UserDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {


    constructor( private authService: AuthService) {
        
    }

    @Post('signup')
    @HttpCode(HttpStatus.CREATED)
    signup(@Body() body: UserDto): Promise<Tokens> {
        return this.authService.signup(body);
    }

    @Post('login')
    @HttpCode(HttpStatus.OK)
    login(@Body() body: AuthDto): Promise<Tokens> {
        return this.authService.login(body);
    }

    @UseGuards(AuthGuard("jwt"))
    @Post('logout')
    @HttpCode(HttpStatus.OK)
    logout(@Req() req: Request): Promise<boolean> {
        const user = req.user
        return this.authService.logout(user['sub']);
    }

    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    refreshTokens() {
        this.authService.refreshTokens();
    }
}
