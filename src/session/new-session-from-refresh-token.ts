import { GetConfig } from '../config';
import { GetClient } from '../auth0-session/client/abstract-client';
import { AccessTokenRequest, SessionCache, fromTokenEndpointResponse, set } from '../session';
import { getAuth0ReqRes } from './cache';
import { Auth0NextRequestCookies } from '../http';
import { IncomingMessage, ServerResponse } from 'http';
import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';

export type NewSessionFromRefreshToken = (
  refreshToken: string,
  ...args:
    | [IncomingMessage, ServerResponse, AccessTokenRequest?]
    | [NextApiRequest, NextApiResponse, AccessTokenRequest?]
    | [NextRequest, NextResponse, AccessTokenRequest?]
    | [AccessTokenRequest?]
) => Promise<void>;

export const newSessionFromRefreshTokenFactory = (
  getConfig: GetConfig,
  getClient: GetClient,
  sessionCache: SessionCache
): NewSessionFromRefreshToken => {
  return async (refreshToken: string, reqOrOpts?, res?, accessTokenRequest?): Promise<void> => {
    const options = (res ? accessTokenRequest : reqOrOpts) as AccessTokenRequest | undefined;
    const req = (res ? reqOrOpts : undefined) as IncomingMessage | NextApiRequest | undefined;

    const config = await getConfig(req ? getAuth0ReqRes(req, res as any)[0] : new Auth0NextRequestCookies());
    const client = await getClient(config);

    const tokenSet = await client.refresh(refreshToken, {
      exchangeBody: options?.authorizationParams
    });

    const newSession = fromTokenEndpointResponse(tokenSet, config);
    Object.assign(newSession, {
      refreshToken: newSession.refreshToken || refreshToken
    });

    await set({ sessionCache, req, res, session: newSession });
  };
};
