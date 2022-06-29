import { BadRequestException, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { DatabaseService } from 'src/database/database.service';
import { AuthDto, UserDto } from './dto';
import * as bcrypt from "bcrypt";
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';


@Injectable()
export class AuthService {


    constructor(private db: DatabaseService, private jwtService: JwtService, private configService: ConfigService) {

    }

    async signup(body: UserDto): Promise<Tokens> {

        const user = await this.findUserByEmail(body.email);

        if (user) throw new ForbiddenException("User Already exists");

        const passwordHash = await this.hashData(body.password);
        const newUser = await this.db.user.create({
            data: {
                firstName: body.firstName,
                lastName: body.lastName,
                email: body.email,
                password: passwordHash
            }
        });

        const tokens = await this.getTokens(newUser.id, newUser.email);
        await this.updateRefreshTokenHash(newUser.id, tokens.refreshToken);
        return tokens;
    }

    async login(data: AuthDto) {
        const user = await this.findUserByEmail(data.email);
        if (!user) throw new UnauthorizedException("User doesn't exists!");

        const passwordMatches = await bcrypt.compare(data.password, user.password);

        if (!passwordMatches) throw new UnauthorizedException("Access Denied!");

        const tokens = await this.getTokens(user.id, user.email);
        await this.updateRefreshTokenHash(user.id, tokens.refreshToken);
        return tokens;
    }

    logout() {

    }

    refreshTokens() {

    }

    private hashData(data: string) {
        return bcrypt.hash(data, 10);
    }

    private async getTokens(userId: number, email: string) {
        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync({
                sub: userId,
                email
            },
                {
                    secret: this.configService.get("ACCESS_TOKEN_SECRET"),
                    expiresIn: 60 * 15
                }
            ),
            this.jwtService.signAsync(
                {
                    sub: userId,
                    email
                },
                {
                    secret: this.configService.get("REFRESH_TOKEN_SECRET"),
                    expiresIn: 60 * 60 * 24 * 7
                }
            )

        ]);

        return {
            accessToken,
            refreshToken
        }

    }

    private async updateRefreshTokenHash(userId: number, refreshToken: string) {
        const refreshTokenHash = await this.hashData(refreshToken);
        await this.db.user.updateMany({
            where: {
                id: userId
            },
            data: {
                hashedRt: refreshTokenHash
            }
        })
    }

    private async findUserByEmail(email: string) {
        const user = await this.db.user.findUnique({
            where: {
                email: email
            }
        });

        return user
    }
}
