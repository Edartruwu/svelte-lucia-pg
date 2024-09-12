import { OAuth2RequestError } from 'arctic';
import { google, lucia } from '$lib/server/auth';
import type { RequestEvent } from '@sveltejs/kit';
import { pool } from '$lib/server/auth';
import { v4 as uuidv4 } from 'uuid';

interface GoogleUser {
	googleId: string;
	name: string;
	email: string;
	picture: string; // Add picture field
}

export async function GET(event: RequestEvent): Promise<Response> {
	const code = event.url.searchParams.get('code');
	const state = event.url.searchParams.get('state');
	const codeVerifier = event.cookies.get('google_oauth_code_verifier');
	const storedState = event.cookies.get('google_oauth_state') ?? null;

	if (!code || !state || !storedState || !codeVerifier || state !== storedState) {
		console.error('Invalid code, state, or code verifier');
		return new Response(null, {
			status: 400
		});
	}

	try {
		const tokens = await google.validateAuthorizationCode(code, codeVerifier);
		const googleUserResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
			headers: {
				Authorization: `Bearer ${tokens.accessToken}`
			}
		});
		const googleUser: GoogleUser = await googleUserResponse.json();

		// Check if user exists in the database
		const existingGoogleUserQuery = `
			SELECT * FROM auth_user WHERE google_id = $1
		`;
		const { rows: existingGoogleUsers } = await pool.query(existingGoogleUserQuery, [
			googleUser.googleId
		]);

		if (existingGoogleUsers.length > 0) {
			const existingGoogleUser = existingGoogleUsers[0];

			// Create a session for the existing user
			const session = await lucia.createSession(existingGoogleUser.id, {});
			const sessionCookie = lucia.createSessionCookie(session.id);
			event.cookies.set(sessionCookie.name, sessionCookie.value, {
				path: '/',
				...sessionCookie.attributes
			});
		} else {
			// Insert new user into the database with picture
			const newUserId = uuidv4();
			const newUserQuery = `
				INSERT INTO auth_user (id, email, google_id, picture_url, created_at, updated_at)
				VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
				RETURNING id
			`;
			const { rows: newUsers } = await pool.query(newUserQuery, [
				newUserId,
				googleUser.email,
				googleUser.googleId,
				googleUser.picture // Save the user's Google profile picture
			]);

			const newUser = newUsers[0];
			const session = await lucia.createSession(newUser.id, {});
			const sessionCookie = lucia.createSessionCookie(session.id);
			event.cookies.set(sessionCookie.name, sessionCookie.value, {
				path: '/',
				...sessionCookie.attributes
			});
		}

		// Redirect the user to the home page after successful login
		return new Response(null, {
			status: 302,
			headers: {
				Location: '/'
			}
		});
	} catch (e) {
		console.error('Error during authentication:', e);
		if (e instanceof OAuth2RequestError) {
			return new Response(null, {
				status: 400
			});
		}
		return new Response(null, {
			status: 500
		});
	}
}
