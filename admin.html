const { createClient } = require('@supabase/supabase-js');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Не авторизован' });

  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

  // Verify caller is admin
  const { data: { user }, error: authError } = await supabase.auth.getUser(token);
  if (authError || !user) return res.status(401).json({ error: 'Не авторизован' });

  const { data: profile } = await supabase.from('profiles').select('is_admin').eq('id', user.id).single();
  if (!profile?.is_admin) return res.status(403).json({ error: 'Доступ запрещён' });

  // GET /api/admin?action=users
  if (req.method === 'GET') {
    const action = req.query.action;
    if (action === 'users') {
      const { data: profiles } = await supabase.from('profiles').select('*').order('created_at', { ascending: false });
      return res.json({ users: profiles || [] });
    }
    if (action === 'estimates') {
      const { userId } = req.query;
      let query = supabase.from('estimates').select('id, title, user_id, created_at, updated_at').order('updated_at', { ascending: false });
      if (userId) query = query.eq('user_id', userId);
      const { data } = await query;
      return res.json({ estimates: data || [] });
    }
    return res.status(400).json({ error: 'Неизвестное действие' });
  }

  // POST /api/admin — create user
  if (req.method === 'POST') {
    const { email, password, isAdmin } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email и пароль обязательны' });

    const { data: newUser, error: createError } = await supabase.auth.admin.createUser({
      email, password, email_confirm: true
    });
    if (createError) return res.status(400).json({ error: createError.message });

    if (isAdmin) {
      await supabase.from('profiles').update({ is_admin: true }).eq('id', newUser.user.id);
    }
    return res.json({ success: true, userId: newUser.user.id });
  }

  // DELETE /api/admin — delete user
  if (req.method === 'DELETE') {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId обязателен' });
    if (userId === user.id) return res.status(400).json({ error: 'Нельзя удалить себя' });

    const { error: delError } = await supabase.auth.admin.deleteUser(userId);
    if (delError) return res.status(400).json({ error: delError.message });
    return res.json({ success: true });
  }

  res.status(405).end();
};
