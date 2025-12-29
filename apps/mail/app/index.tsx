import { redirect } from 'react-router';

export function clientLoader() {
  return redirect('/mail/inbox');
}

export default function Index() {
  return null;
}
