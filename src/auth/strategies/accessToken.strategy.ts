import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import {Secret} from "../../common/enums/secret.enum";


type JwtPayload = {
    sub: number;
    email: string;
    iat: number;
    exp: number;
}

@Injectable()
export class AccessTokenStrategy extends PassportStrategy(Strategy, 'jwt') {
    /**
     *
     */
    constructor(private configService: ConfigService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: configService.get(Secret.ACCESS_TOKEN_SECRET)
        });
    }

    validate(payload: JwtPayload) {
        return payload;
    }
}