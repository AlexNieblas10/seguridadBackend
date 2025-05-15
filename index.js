import express from 'express'
import cors from 'cors'
import CryptoJS from 'crypto-js'
import { db } from './db.js'

const app = express()

app.use(cors({
  origin: '*',
  credentials: false,
}))
app.use(express.json())

const CLAVE_SECRETA = CryptoJS.enc.Utf8.parse('12345678')

function cifrarDES(texto) {
  const mensaje = CryptoJS.enc.Utf8.parse(texto)
  const cifrado = CryptoJS.DES.encrypt(mensaje, CLAVE_SECRETA, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
  })
  return cifrado.toString()
}

app.post('/register', async (req, res) => {
  const { usuario, password } = req.body
  try {
    const [rows] = await db.query('SELECT 1 FROM usuarios WHERE username = ?', [usuario])
    if (rows.length > 0) return res.status(400).json({ error: 'Usuario ya existe' })

    const passwordCifrada = cifrarDES(password)
    await db.query('INSERT INTO usuarios (username, password) VALUES (?, ?)', [usuario, passwordCifrada])
    res.json({ mensaje: 'Registrado' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Error en el servidor' })
  }
})

app.post('/login', async (req, res) => {
  const { usuario, password } = req.body
  try {
    const passwordCifrada = cifrarDES(password)
    const [rows] = await db.query(
      'SELECT username FROM usuarios WHERE username = ? AND password = ?',
      [usuario, passwordCifrada]
    )
    if (rows.length === 0) return res.status(401).json({ error: 'Usuario o contraseña incorrecta' })

    res.json({ mensaje: 'Login exitoso' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Error en el servidor' })
  }
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`)
})
