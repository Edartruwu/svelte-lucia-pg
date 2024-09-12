import { Lucia } from 'lucia';
import { Google } from 'arctic';
import { NodePostgresAdapter } from '@lucia-auth/adapter-postgresql';
import pg from 'pg';
import {
	GOOGLE_CLIENT_ID,
	GOOGLE_CLIENT_SECRET,
	CALLBACK_URL,
	DB_USER,
	DB_HOST,
	DB_PORT,
	DB_PASSWORD,
	DB_NAME
} from '$env/static/private';

export const google = new Google(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, CALLBACK_URL);

export const pool = new pg.Pool({
	user: DB_USER,
	host: DB_HOST,
	port: Number(DB_PORT),
	password: DB_PASSWORD,
	database: DB_NAME
});

const adapter = new NodePostgresAdapter(pool, {
	user: 'auth_user',
	session: 'user_session'
});

export const lucia = new Lucia(adapter, {
	sessionCookie: {
		attributes: {
			secure: false
		}
	},
	getUserAttributes: (attributes) => {
		return {
			googleId: attributes.googleId,
			name: attributes.name,
			email: attributes.email,
			picture: attributes.picture
		};
	}
});

declare module 'lucia' {
	interface Register {
		Lucia: typeof lucia;
		DatabaseUserAttributes: DatabaseUserAttributes;
	}
}

interface DatabaseUserAttributes {
	googleId: string;
	name: string;
	email: string;
	picture: string;
}
