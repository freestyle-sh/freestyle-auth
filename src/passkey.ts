import { useRequest } from "freestyle-sh";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type VerifiedRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/types";
import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";

export type FinishPasskeyAuthenticationJSON = AuthenticationResponseJSON;
export type FinishPasskeyRegistrationJSON = RegistrationResponseJSON;

export interface DefiniteAuthenticatorCS<
  UserCS extends BaseUserCS = BaseUserCS
> {
  getCurrentUser(): UserCS | undefined;
  getDefiniteCurrentUser(): UserCS;
}

export interface BaseUserCS {
  id: string;
  username: string;
}

export const handlePasskeyAuthentication = startAuthentication;
export const handlePasskeyRegistration = startRegistration;

function getSessionId() {
  const request = useRequest();
  const cookies = parseCookie(request.headers.get("cookie") ?? "");

  const sessionId = cookies.get("freestyle-session-id");
  if (!sessionId) {
    throw new Error("No session ID");
  }
  return sessionId;
}

function parseCookie(str: string) {
  return str
    .split(";")
    .map((v) => v.split("="))
    .reduce((acc, v) => {
      acc.set(
        decodeURIComponent(v[0].trim()),
        decodeURIComponent(v[1]?.trim() ?? "")
      );
      return acc;
    }, new Map<string, string>());
}

export class PasskeyAuthentication implements DefiniteAuthenticatorCS {
  registrationSessions = new Map<
    string,
    PublicKeyCredentialCreationOptionsJSON
  >();

  authenticationSessions = new Map<
    string,
    { options: PublicKeyCredentialRequestOptionsJSON; username: string }
  >();

  userRegistrations = new Map<
    string,
    {
      registrations: Set<
        NonNullable<VerifiedRegistrationResponse["registrationInfo"]>
      >;
    }
  >();

  sessions = new Map<
    string,
    {
      userId: string;
    }
  >();

  usernames = new Map<
    string,
    {
      userId: string;
    }
  >();

  userIds = new Map<
    string,
    {
      username: string;
    }
  >();

  async startAuthenticationOrRegistration(username: string) {
    const userId = this.usernames.get(username)?.userId;
    if (!userId) {
      return {
        signup: await this.startRegistration(username),
      };
    }

    return {
      login: await this.startAuthentication(username),
    };
  }

  async startRegistration(username: string) {
    const sessionId = getSessionId();

    if (this.usernames.has(username)) {
      throw new Error("Username already taken");
    }

    const options = await generateRegistrationOptions({
      rpName: "Freestyle Feature Requests",
      rpID: "localhost",
      userID: Uint8Array.from(crypto.randomUUID(), (c) => c.charCodeAt(0)),
      userName: username,
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "discouraged",
      },
      userDisplayName: username,
    });

    this.registrationSessions.set(sessionId, options);

    return options;
  }

  async finishRegistration(
    registrationResponse: RegistrationResponseJSON
  ): Promise<BaseUserCS> {
    const sessionId = getSessionId();

    const registrationSession = this.registrationSessions.get(sessionId);
    if (!registrationSession) {
      throw new Error("No registration session");
    }

    const credential = await verifyRegistrationResponse({
      response: registrationResponse,
      expectedChallenge: registrationSession.challenge,
      expectedOrigin: "https://localhost:4321",
      expectedRPID: "localhost",
    }).catch((e) => {
      console.error(e);
      throw new Error("Registration response not verified");
    });

    if (!credential.verified) {
      throw new Error("Credential not verified");
    }

    let user = this.userRegistrations.get(registrationSession.user.id);

    if (!user) {
      user = {
        registrations: new Set(),
      };
      this.userRegistrations.set(registrationSession.user.id, user);
    }

    if (!credential.registrationInfo) {
      throw new Error("Could not create registration info");
    }

    user.registrations.add(credential.registrationInfo);

    this.sessions.set(sessionId, {
      userId: registrationSession.user.id,
    });

    this.registrationSessions.delete(sessionId);

    this.usernames.set(registrationSession.user.name, {
      userId: registrationSession.user.id,
    });
    this.userIds.set(registrationSession.user.id, {
      username: registrationSession.user.name,
    });

    return {
      id: registrationSession.user.id,
      username: registrationSession.user.name,
    };
  }

  async startAuthentication(username: string) {
    const sessionId = getSessionId();

    const userId = this.usernames.get(username)?.userId;
    if (!userId) {
      throw new Error("User not found");
    }

    const user = this.userRegistrations.get(userId);
    if (!user) {
      throw new Error("No user registrations found for this session");
    }

    const rpID = "localhost";

    const options: PublicKeyCredentialRequestOptionsJSON =
      await generateAuthenticationOptions({
        rpID,
        // Require users to use a previously-registered authenticator
        allowCredentials: Array.from(user.registrations.values()).map(
          (registration) => ({
            id: registration.credentialID,
          })
        ),
      });

    this.authenticationSessions.set(sessionId, { username: username, options });

    return options;
  }

  async finishAuthentication(
    authenticationResponse: AuthenticationResponseJSON
  ): Promise<BaseUserCS> {
    const sessionId = getSessionId();
    const options = this.authenticationSessions.get(sessionId);
    if (!options) {
      throw new Error("No authentication options found for this session");
    }

    const userId = this.usernames.get(options.username)?.userId;
    if (!userId) {
      throw new Error("User not found");
    }

    const user = this.userRegistrations.get(userId);
    if (!user) {
      throw new Error("No user registrations found for this session");
    }

    const passkey = Array.from(user.registrations.values())?.find(
      (passkey) => passkey.credentialID === authenticationResponse.id
    );
    if (!passkey) {
      throw new Error("No passkey found for this user");
    }

    const rpID = "localhost";
    const origin = "https://localhost:4321";

    const credential = await verifyAuthenticationResponse({
      response: authenticationResponse,
      expectedChallenge: options.options.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: passkey.credentialID,
        credentialPublicKey: passkey.credentialPublicKey,
        counter: passkey.counter,
      },
    });

    if (!credential.verified) {
      throw new Error("Credential not verified");
    }

    this.sessions.set(sessionId, {
      userId: userId,
    });

    this.authenticationSessions.delete(sessionId);

    return { id: userId, username: options.username };
  }

  getCurrentUser(): BaseUserCS | undefined {
    const userId = this.sessions.get(getSessionId())?.userId;
    if (!userId) return;
    const userName = this.userIds.get(userId)?.username;

    if (!userName) {
      throw new Error(
        "Username not found for user. This should never happen. Please report this bug."
      );
    }

    return {
      id: userId,
      username: userName,
    };
  }

  getDefiniteCurrentUser(): BaseUserCS {
    const user = this.getCurrentUser();
    if (!user) {
      throw new Error("User not found");
    }
    return user;
  }
}
