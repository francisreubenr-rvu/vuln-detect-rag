import { useState, useEffect } from 'react'
import { Bot, RefreshCw, Database, MessageSquare, Trash2 } from 'lucide-react'
import { chatRAG, getChatHistory, listSessions, deleteSession } from '../api/client'
import ChatPanel from '../components/ChatPanel'

export default function RAGAssistant() {
  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(false)
  const [sessionId, setSessionId] = useState(`session_${Date.now()}`)
  const [sessions, setSessions] = useState([])

  useEffect(() => {
    loadSessions()
  }, [])

  const loadSessions = async () => {
    try {
      const { data } = await listSessions()
      setSessions(data)
    } catch (err) {
      console.error(err)
    }
  }

  const loadSession = async (sid) => {
    setSessionId(sid)
    try {
      const { data } = await getChatHistory(sid)
      setMessages(data.map(m => ({
        role: m.role,
        content: m.content,
        sources: m.sources || [],
      })))
    } catch (err) {
      console.error(err)
    }
  }

  const handleSend = async (message) => {
    setMessages((prev) => [...prev, { role: 'user', content: message }])
    setLoading(true)

    try {
      const { data } = await chatRAG(message, sessionId)
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: data.answer,
          sources: data.sources,
        },
      ])
      loadSessions()
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: 'Sorry, I encountered an error processing your request. Please make sure the backend is running.',
          sources: [],
        },
      ])
    } finally {
      setLoading(false)
    }
  }

  const clearChat = () => {
    setMessages([])
    setSessionId(`session_${Date.now()}`)
  }

  const handleDeleteSession = async (sid) => {
    try {
      await deleteSession(sid)
      if (sid === sessionId) clearChat()
      loadSessions()
    } catch (err) {
      console.error(err)
    }
  }

  return (
    <div className="h-full flex flex-col min-w-0">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold text-white">RAG Assistant</h1>
          <p className="text-dark-400 text-sm mt-1">
            AI-powered vulnerability intelligence
          </p>
        </div>
        <button
          onClick={clearChat}
          className="px-3 py-2 bg-dark-800 border border-dark-600 rounded-lg text-sm text-dark-300 hover:text-white flex items-center gap-2 flex-shrink-0"
        >
          <RefreshCw className="w-4 h-4" />
          New Chat
        </button>
      </div>

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Session History Sidebar */}
        {sessions.length > 0 && (
          <div className="hidden lg:flex w-56 flex-shrink-0 bg-dark-900 border border-dark-700 rounded-lg flex-col">
            <div className="p-3 border-b border-dark-700">
              <h3 className="text-xs font-semibold text-dark-400 uppercase">Sessions</h3>
            </div>
            <div className="flex-1 overflow-auto divide-y divide-dark-700">
              {sessions.map((s) => (
                <div
                  key={s.session_id}
                  className={`px-3 py-2 flex items-center justify-between cursor-pointer hover:bg-dark-800 transition-colors ${
                    s.session_id === sessionId ? 'bg-dark-800' : ''
                  }`}
                  onClick={() => loadSession(s.session_id)}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <MessageSquare className="w-3 h-3 text-dark-500 flex-shrink-0" />
                    <span className="text-xs text-dark-300 truncate">
                      {s.message_count} messages
                    </span>
                  </div>
                  <button
                    onClick={(e) => { e.stopPropagation(); handleDeleteSession(s.session_id) }}
                    className="text-dark-600 hover:text-red-400 flex-shrink-0"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Chat Panel */}
        <div className="flex-1 bg-dark-900 border border-dark-700 rounded-lg overflow-hidden">
          <ChatPanel messages={messages} onSend={handleSend} loading={loading} />
        </div>
      </div>

      {/* Info footer */}
      <div className="mt-3 flex items-center gap-4 text-xs text-dark-500">
        <div className="flex items-center gap-1">
          <Database className="w-3 h-3" />
          <span>Knowledge base: 50+ CVEs indexed</span>
        </div>
        <div className="flex items-center gap-1">
          <Bot className="w-3 h-3" />
          <span>RAG with ChromaDB + LangChain</span>
        </div>
      </div>
    </div>
  )
}
