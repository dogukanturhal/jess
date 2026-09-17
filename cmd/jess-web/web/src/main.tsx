// jess-web SPA entry — C2 command-center IA.
//
// The Go server hosts the SPA shell on / (+ deep routes) and serves the
// server-rendered surfaces (/auth/*, /api/*, /ws/*) directly; the SPA never
// touches those. Routes below are pure client-side navigation over the SAME
// API/WS/auth surface — only presentation + IA changed in the C2 reskin.
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'

// IBM Carbon Design System (g100 dark theme) + Plex fonts + the token bridge
// that retargets the legacy --hxm-* / --c2-* custom properties onto Carbon
// tokens. Imported FIRST so the structural stylesheets below resolve against
// Carbon's g100 palette. (tokens.css is intentionally dropped — carbon.scss is
// now the single source of design tokens.)
import './styles/carbon.scss'
import '@xterm/xterm/css/xterm.css'
import './styles/app.css'
import './styles/c2.css'

import { CommandPalette } from './components/CommandPalette'
import { ConsoleDock, ConsoleDockProvider } from './components/c2'
import { Admin } from './pages/Admin'
import { DBConsole } from './pages/DBConsole'
import { DevicePreReg } from './pages/DevicePreReg'
import { Overview } from './pages/Overview'
import { Pending } from './pages/Pending'
import { RDP } from './pages/RDP'
import { RDPRecordings } from './pages/RDPRecordings'
import { Recording } from './pages/Recording'
import { Session } from './pages/Session'
import { TargetDetail } from './pages/TargetDetail'
import { Targets } from './pages/Targets'

const root = document.getElementById('root')
if (!root) throw new Error('jess-web: #root missing from index.html')

createRoot(root).render(
  <StrictMode>
    <BrowserRouter>
      <ConsoleDockProvider>
      <Routes>
        {/* Overview / inventory dashboard */}
        <Route path="/" element={<Overview />} />

        {/* Inventory */}
        <Route path="/targets" element={<Targets />} />
        <Route path="/targets/:id" element={<TargetDetail />} />

        {/* Admin / control surfaces (each tab is now its own rail route) */}
        <Route path="/admin/requests" element={<Admin tab="requests" />} />
        <Route path="/admin/sessions" element={<Admin tab="sessions" />} />
        <Route path="/admin/grants" element={<Admin tab="grants" />} />
        <Route path="/admin/catalog" element={<Admin tab="catalog" />} />
        <Route path="/admin/pending" element={<Pending />} />
        <Route path="/admin/devices" element={<DevicePreReg />} />
        <Route path="/admin/audit" element={<Admin tab="audit" />} />
        {/* Legacy /admin → first control surface */}
        <Route path="/admin" element={<Navigate to="/admin/requests" replace />} />

        {/* Live consoles + playback (wrapped in the shell; PASS 2 polishes) */}
        <Route path="/session" element={<Session />} />
        <Route path="/db-console" element={<DBConsole />} />
        <Route path="/recordings/:sessionId" element={<Recording />} />
        <Route path="/rdp/recordings" element={<RDPRecordings />} />
        <Route path="/rdp/recordings/:sessionId" element={<RDPRecordings />} />
        <Route path="/rdp/:targetId" element={<RDP />} />

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      {/* Global Cmd+K palette — outside Routes so it persists across navs. */}
      <CommandPalette />
      {/* Live remote-console dock — also outside Routes so sessions stay
          mounted (connected) while the operator browses other pages. */}
      <ConsoleDock />
      </ConsoleDockProvider>
    </BrowserRouter>
  </StrictMode>,
)
