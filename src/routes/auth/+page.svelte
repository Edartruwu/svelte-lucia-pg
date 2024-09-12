<script>
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
</script>

<main class="flex h-screen w-screen flex-col items-center justify-center">
	<Card.Root class="flex flex-col items-center justify-center">
		<Card.Header>
			<Card.Title>Ingresa a Vendy</Card.Title>
			<Card.Description>Haz click a un botón para continuar</Card.Description>
		</Card.Header>
		<Card.Content>
			<a href={'/auth/google'}>
				<Button variant={'outline'}>Continua con google</Button>
			</a>
		</Card.Content>
		<Card.Footer>
			<p class="text-sm text-muted-foreground">Contactar a soporte</p>
		</Card.Footer>
	</Card.Root>
</main>
