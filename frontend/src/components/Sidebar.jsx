import { NavLink } from 'react-router-dom'
import { Shield, LayoutDashboard, Scan, MessageSquare, Activity, Database, Sun, Moon } from 'lucide-react'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scans', icon: Scan, label: 'Scan Console' },
  { to: '/rag', icon: MessageSquare, label: 'RAG Assistant' },
  { to: '/cve', icon: Database, label: 'CVE Database' },
]

export default function Sidebar({ theme, onToggleTheme }) {
  return (
    <aside className="w-64 bg-dark-900 border-r border-dark-700 flex flex-col">
      <div className="p-5 border-b border-dark-700">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-red-500 to-orange-500 rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">VulnDetectRAG</h1>
            <p className="text-xs text-dark-400">Vulnerability Intelligence</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4 space-y-1">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-dark-800 text-white border border-dark-600'
                  : 'text-dark-300 hover:bg-dark-800 hover:text-white'
              }`
            }
          >
            <Icon className="w-5 h-5" />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-dark-700 space-y-3">
        <button
          onClick={onToggleTheme}
          className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-dark-400 hover:text-white hover:bg-dark-800 transition-colors"
        >
          {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
        </button>
        <div className="flex items-center gap-2 text-xs text-dark-500">
          <Activity className="w-3 h-3" />
          <span>v1.0.0</span>
        </div>
      </div>
    </aside>
  )
}
