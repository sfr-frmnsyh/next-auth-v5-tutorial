"use client";

import { useCurrenRole } from "@/hooks/use-current-role";
import { FormError } from "@/components/form-error";

interface RoleGateProps {
  children: React.ReactNode;
  allowedRole: string[];
}

export const RoleGate = ({ children, allowedRole }: RoleGateProps) => {
  const role = useCurrenRole();

  if (!allowedRole.includes(role as string)) {
    return (
      <div>
        <FormError message="You do not have permission to view this content!" />
      </div>
    );
  }

  return <>{children}</>;
};
