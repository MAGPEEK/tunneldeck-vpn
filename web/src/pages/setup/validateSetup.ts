export interface SetupValues {
  username: string;
  password: string;
  repeatPassword: string;
}

export type SetupErrorKey =
  'setup.usernameLength' | 'setup.passwordLength' | 'setup.passwordMismatch';
export type SetupErrors = Partial<Record<keyof SetupValues, SetupErrorKey>>;

export const USERNAME_MIN = 3;
export const USERNAME_MAX = 32;
export const PASSWORD_MIN = 12;

export function validateSetup({ username, password, repeatPassword }: SetupValues): SetupErrors {
  const errors: SetupErrors = {};
  const usernameLength = username.trim().length;
  if (usernameLength < USERNAME_MIN || usernameLength > USERNAME_MAX) {
    errors.username = 'setup.usernameLength';
  }
  if (password.length < PASSWORD_MIN) {
    errors.password = 'setup.passwordLength';
  }
  if (repeatPassword !== password) {
    errors.repeatPassword = 'setup.passwordMismatch';
  }
  return errors;
}
