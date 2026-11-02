import type { ActionFunctionArgs, MetaFunction } from "@remix-run/node";
import { redirect } from "@remix-run/node";
import {
  Form,
  Link,
  useActionData,
  useNavigation,
  useSearchParams,
} from "@remix-run/react";

import { commitSession, getSession } from "~/session.server";

import Button from "~/components/Button";
import TextField from "~/components/TextField";
import { getSupabaseClient } from "~/utils/getSupabaseClient";

export const meta: MetaFunction = () => {
  return [
    {
      title: "Sign Up | Remix Dashboard",
    },
  ];
};

export async function action({ request }: ActionFunctionArgs) {
  const formData = await request.formData();
  const name = formData.get("name");
  const email = formData.get("email");
  const password = formData.get("password");

  if (
    typeof name !== "string" ||
    typeof email !== "string" ||
    typeof password !== "string" ||
    !name.trim() ||
    !email.trim() ||
    !password
  ) {
    return Response.json(
      { error: "Name, email and password must be provided." },
      { status: 400 }
    );
  }

  const supabase = getSupabaseClient();
  const { data, error } = await supabase.auth.signUp({
    email: email.trim(),
    password,
    options: { data: { name: name.trim() } },
  });

  if (error) {
    return Response.json({ error: error.message }, { status: 400 });
  }

  if (!data.session) {
    // Email confirmation is required before the user can sign in.
    return Response.json({
      message: "Account created. Check your email to confirm your address.",
    });
  }

  const session = await getSession(request.headers.get("Cookie"));
  session.set("__session", data.session.access_token);

  return redirect("/dashboard", {
    headers: {
      "Set-Cookie": await commitSession(session),
    },
  });
}

export default function SignUp() {
  const actionData = useActionData<{ error?: string; message?: string }>();
  const navigation = useNavigation();
  const [searchParams] = useSearchParams();

  const isSubmitting = navigation.state === "submitting";

  return (
    <div className="w-full max-w-2xl px-8 py-10 space-y-8 bg-white shadow-md rounded-xl lg:space-y-10 lg:px-10 lg:py-12 ">
      <div className="space-y-3">
        <h1 className="text-2xl font-semibold text-slate-900 sm:text-3xl lg:text-4xl">
          Sign Up for Remix Dashboard
        </h1>
        <p className="text-sm">
          Already have an account?{" "}
          <Link
            className="underline text-cyan-600"
            to={{
              pathname: "/login",
              search: searchParams.toString(),
            }}
          >
            Sign in
          </Link>
        </p>
      </div>
      <Form method="POST">
        {actionData?.error && (
          <p className="p-3 mb-4 text-sm rounded-md bg-rose-50 text-rose-700">
            {actionData.error}
          </p>
        )}
        {actionData?.message && (
          <p className="p-3 mb-4 text-sm rounded-md bg-cyan-50 text-cyan-700">
            {actionData.message}
          </p>
        )}
        <fieldset
          className="w-full space-y-4 lg:space-y-6 disabled:opacity-70"
          disabled={isSubmitting}
        >
          <TextField
            id="name"
            name="name"
            label="Name"
            required
            type="text"
            placeholder="Name Surname"
          />
          <TextField
            id="email"
            name="email"
            label="Email address"
            required
            type="email"
            placeholder="Email address"
          />
          <TextField
            id="password"
            name="password"
            label="Password"
            required
            type="password"
            placeholder="password"
          />
          <Button type="submit" className="w-full" loading={isSubmitting}>
            Sign Up
          </Button>
        </fieldset>
      </Form>
    </div>
  );
}
