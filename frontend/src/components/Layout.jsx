import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'

export default function Layout({ theme, onToggleTheme }) {
  return (
    <div className="flex h-screen bg-dark-950">
      <Sidebar theme={theme} onToggleTheme={onToggleTheme} />
      <main className="flex-1 overflow-auto p-6">
        <Outlet />
      </main>
    </div>
  )
}
