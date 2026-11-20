import { createClient } from 'jsr:@supabase/supabase-js@2';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, 'Content-Type': 'application/json' } });

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405);

  const adm = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    { auth: { autoRefreshToken: false, persistSession: false } },
  );

  const jwt = (req.headers.get('Authorization') || '').replace('Bearer ', '');
  const { data: { user }, error } = await adm.auth.getUser(jwt);
  if (error || !user) return json({ error: 'Tidak terautentikasi' }, 401);

  const { data: me } = await adm.from('profiles').select('role,aktif').eq('id', user.id).single();
  if (!me || me.role !== 'kepala' || !me.aktif)
    return json({ error: 'Hanya kepala produksi yang boleh mengelola pengguna' }, 403);

  let p: Record<string, string>;
  try { p = await req.json(); } catch { return json({ error: 'Body tidak valid' }, 400); }

  try {
    if (p.action === 'create') {
      const kode = String(p.kode || '').toLowerCase().trim();
      if (!/^[a-z0-9._-]{3,24}$/.test(kode)) return json({ error: 'Kode akun 3–24 karakter (huruf/angka)' }, 400);
      if (!p.password || p.password.length < 6) return json({ error: 'Kata sandi minimal 6 karakter' }, 400);
      if (!['kepala','admin','operator'].includes(p.role)) return json({ error: 'Peran tidak valid' }, 400);

      const { data, error: e1 } = await adm.auth.admin.createUser({
        email: p.email || `${kode}@mhi.local`,
        password: p.password,
        email_confirm: true,
      });
      if (e1) return json({ error: e1.message }, 400);

      const { error: e2 } = await adm.from('profiles').insert({
        id: data.user!.id, kode, nama: p.nama, role: p.role,
        jabatan: p.jabatan || null, mesin: p.mesin || null,
        warna: p.warna || '#5C6270', aktif: true,
      });
      if (e2) { await adm.auth.admin.deleteUser(data.user!.id); return json({ error: e2.message }, 400); }
      return json({ ok: true, id: data.user!.id });
    }

    if (p.action === 'reset') {
      if (!p.id || !p.password || p.password.length < 6) return json({ error: 'Data tidak lengkap' }, 400);
      const { error: e } = await adm.auth.admin.updateUserById(p.id, { password: p.password });
      return e ? json({ error: e.message }, 400) : json({ ok: true });
    }

    if (p.action === 'delete') {
      if (!p.id) return json({ error: 'ID wajib' }, 400);
      if (p.id === user.id) return json({ error: 'Tidak dapat menghapus akun sendiri' }, 400);
      const { count } = await adm.from('reports').select('id', { count: 'exact', head: true }).eq('operator_id', p.id);
      if ((count ?? 0) > 0) return json({ error: 'Akun punya laporan — nonaktifkan saja agar arsip utuh.' }, 400);
      const { error: e } = await adm.auth.admin.deleteUser(p.id);
      return e ? json({ error: e.message }, 400) : json({ ok: true });
    }

    return json({ error: 'Aksi tidak dikenal' }, 400);
  } catch (e) {
    return json({ error: (e as Error).message }, 500);
  }
});
