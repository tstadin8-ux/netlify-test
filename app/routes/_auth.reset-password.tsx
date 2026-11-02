import type { ActionFunctionArgs, MetaFunction } from "@remix-run/node";
import { Form, useActionData, useNavigation } from "@remix-run/react";

import Button from "~/components/Button";
import TextField from "~/components/TextField";
import { getSupabaseClient } from "~/utils/getSupabaseClient";

export const meta: MetaFunction = () => {
  return [
    {
      title: "Reset password | Remix Dashboard",
    },
  ];
};

export async function action({ request }: ActionFunctionArgs) {
  const formData = await request.formData();
  const email = formData.get("email");

  if (typeof email !== "string" || !email) {
    return Response.json(
      { error: "Email address must be provided." },
      { status: 400 }
    );
  }

  const supabase = getSupabaseClient();
  const { error } = await supabase.auth.resetPasswordForEmail(email);

  if (error) {
    return Response.json({ error: error.message }, { status: 400 });
  }

  return Response.json({
    success: "If an account exists for that email, a reset link has been sent.",
  });
}

export default function ResetPassword() {
  const actionData = useActionData<{ error?: string; success?: string }>();
  const navigation = useNavigation();

  const isSubmitting = navigation.state === "submitting";

  return (
    <div className="w-full max-w-2xl px-8 py-10 space-y-8 bg-white shadow-md rounded-xl lg:space-y-10 lg:px-10 lg:py-12 ">
      <h1 className="text-2xl font-semibold text-slate-900 sm:text-3xl lg:text-4xl">
        Forgot your password?
      </h1>
      <Form method="POST" className="w-full space-y-4 lg:space-y-6">
        {actionData?.error && (
          <p className="p-3 text-sm rounded-md bg-rose-50 text-rose-700">
            {actionData.error}
          </p>
        )}
        {actionData?.success && (
          <p className="p-3 text-sm rounded-md bg-cyan-50 text-cyan-700">
            {actionData.success}
          </p>
        )}
        <TextField
          id="email"
          name="email"
          label="Email address"
          required
          type="email"
          placeholder="Email address"
        />
        <Button type="submit" className="w-full" loading={isSubmitting}>
          Reset Password
        </Button>
      </Form>
    </div>
  );
}
