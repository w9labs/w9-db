'use client'

export default function Home() {
    return (
        <main className="w-full max-w-[800px] flex flex-col gap-6">
            <header className="header flex justify-between items-center border border-border p-4 bg-black/50 backdrop-blur">
                <div>
                    <h1 className="text-xl font-bold tracking-[0.2em] uppercase">W9 Database</h1>
                    <p className="text-xs text-gray-500 uppercase tracking-widest mt-1">Centralized Data Node</p>
                </div>
                <div className="flex gap-2">
                    <div className="h-2 w-2 rounded-full bg-accent animate-pulse"></div>
                    <span className="text-xs text-accent uppercase tracking-widest">Online</span>
                </div>
            </header>

            <section className="box">
                <h2 className="text-lg uppercase tracking-widest mb-4 border-b border-border pb-2">System Status</h2>
                <div className="grid grid-cols-2 gap-4">
                    <div className="border border-border p-4 bg-black">
                        <div className="text-xs text-gray-500 uppercase">Connections</div>
                        <div className="text-2xl font-bold mt-1">5/100</div>
                    </div>
                    <div className="border border-border p-4 bg-black">
                        <div className="text-xs text-gray-500 uppercase">Storage</div>
                        <div className="text-2xl font-bold mt-1">1.2 GB</div>
                    </div>
                </div>
            </section>

            <section className="box">
                <h2 className="text-lg uppercase tracking-widest mb-4 border-b border-border pb-2">Managed Services</h2>
                <div className="flex flex-col gap-2">
                    <div className="flex justify-between items-center border border-border p-3 hover:bg-white/5 transition-colors cursor-pointer group">
                        <span className="uppercase tracking-wide group-hover:text-white transition-colors">w9-tools</span>
                        <span className="text-xs text-gray-500">PostgreSQL</span>
                    </div>
                    <div className="flex justify-between items-center border border-border p-3 hover:bg-white/5 transition-colors cursor-pointer group">
                        <span className="uppercase tracking-wide group-hover:text-white transition-colors">w9-mail</span>
                        <span className="text-xs text-gray-500">PostgreSQL</span>
                    </div>
                    <div className="flex justify-between items-center border border-border p-3 hover:bg-white/5 transition-colors cursor-pointer group">
                        <span className="uppercase tracking-wide group-hover:text-white transition-colors">w9-reminders</span>
                        <span className="text-xs text-gray-500">PostgreSQL</span>
                    </div>
                </div>
            </section>

            <section className="box flex justify-center py-8">
                <button className="button accent">Manage Database</button>
            </section>
        </main>
    )
}
