import * as React from "react"
import { cn } from "../../lib/utils"

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'destructive' | 'outline' | 'ghost' | 'tactical';
  size?: 'default' | 'sm' | 'lg' | 'icon';
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'default', ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-tactical-600 disabled:pointer-events-none disabled:opacity-50",
          {
            "bg-nit-green text-tactical-900 hover:bg-nit-green/90 shadow-[0_0_15px_rgba(0,255,102,0.3)]": variant === 'default',
            "bg-nit-red text-tactical-900 hover:bg-nit-red/90 shadow-[0_0_15px_rgba(255,51,102,0.3)]": variant === 'destructive',
            "border border-tactical-600 bg-transparent hover:bg-tactical-700 text-tactical-100": variant === 'outline',
            "hover:bg-tactical-700 hover:text-tactical-100": variant === 'ghost',
            "bg-tactical-700 text-nit-green border border-nit-green hover:bg-nit-green/10": variant === 'tactical',
            "h-9 px-4 py-2": size === 'default',
            "h-8 rounded-md px-3 text-xs": size === 'sm',
            "h-10 rounded-md px-8": size === 'lg',
            "h-9 w-9": size === 'icon',
          },
          className
        )}
        {...props}
      />
    )
  }
)
Button.displayName = "Button"

export { Button }
