"use server";

import * as z from "zod";
import { db } from "@/lib/db";
import { LoginSchema } from "@/schemas";
import { signIn } from "@/auth";
import { DEFAULT_LOGIN_REDIRECT } from "@/routes";
import { AuthError } from "next-auth";
import { getUserByEmail } from "@/data/user";
import { generateVerificationToken, generateTwoFactorToken } from "@/lib/token";
import { sendVerificationEmail, sendTwoFactorTokenEmail } from "@/lib/mail";
import { getTwoFactorTokenByEmail } from "@/data/two-factor-token";
import { getTwoFactorConfirmationByUserId } from "@/data/two-factor-confirmation";

export const login = async (
  values: z.infer<typeof LoginSchema>,
  callbackUrl?: string | null
) => {
  const validatedFields = LoginSchema.safeParse(values);

  if (!validatedFields.success) {
    return { error: "Invalid fields!" };
  }

  const { email, password, code } = validatedFields.data;

  const existingUser = await getUserByEmail(email);

  if (!existingUser || !existingUser.email || !existingUser.password) {
    return { error: "Invalid credentials!" };
  }

  if (!existingUser.emailVerified) {
    const verificationToken = await generateVerificationToken(
      existingUser.email
    );

    await sendVerificationEmail(
      verificationToken.email,
      verificationToken.token
    );

    return { success: "Confirmation email sent!" };
  }

  // Two Factor Function
  if (existingUser.isTwoFactorEnabled && existingUser.email) {
    if (code) {
      const twoFactorToken = await getTwoFactorTokenByEmail(existingUser.email);

      if (!twoFactorToken) {
        return { error: "Invalid code!" };
      }
      if (twoFactorToken.token !== code) {
        return { error: "Invalid code!" };
      }

      const hasExpired = new Date(twoFactorToken.expires) < new Date();
      if (hasExpired) {
        return { error: "Code expired!" };
      }

      await db.twoFactorToken.delete({
        where: { id: twoFactorToken.id },
      });

      const existingConfimation = await getTwoFactorConfirmationByUserId(
        existingUser.id
      );
      if (existingConfimation) {
        await db.twoFactorConfirmation.delete({
          where: { id: existingConfimation.id },
        });
      }

      await db.twoFactorConfirmation.create({
        data: {
          userId: existingUser.id,
        },
      });
    } else {
      const twoFactorToken = await generateTwoFactorToken(existingUser.email);
      await sendTwoFactorTokenEmail(twoFactorToken.email, twoFactorToken.token);

      return { twoFactor: true };
    }
  }

  try {
    await signIn("credentials", {
      email,
      password,
      redirectTo: callbackUrl || DEFAULT_LOGIN_REDIRECT,
    });
  } catch (error) {
    if (error instanceof AuthError) {
      // console.log(error.message);
      switch (error.type) {
        case "CredentialsSignin":
          return { error: "Invalid credentials!" };
        case "CallbackRouteError":
          if (
            error.cause &&
            typeof error.cause === "object" &&
            "err" in error.cause
          ) {
            const cause = error.cause as { err: { code?: string } };
            if (cause.err && cause.err.code === "credentials") {
              return { error: "Invalid credentials" };
            } else {
              return { error: "Something went wrong!" };
            }
          }
        default:
          return { error: "Something went wrong!" };
      }
    }

    throw error;
  }
};
