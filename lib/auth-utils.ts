import { db } from "@/lib/db"
import { hashPassword } from "./auth"

export async function createUser(data: {
  email: string
  password: string
  name?: string
  phone?: string
  role?: "RETAIL" | "WHOLESALE" | "ADMIN"
}) {
  const hashedPassword = await hashPassword(data.password)
  
  const user = await db.user.create({
    data: {
      email: data.email,
      password: hashedPassword,
      name: data.name,
      phone: data.phone,
      role: data.role || "RETAIL",
    }
  })
  
  return user
}

export async function createAdminUser() {
  const existingAdmin = await db.user.findUnique({
    where: { email: "admin@barcodephone.com" }
  })
  
  if (!existingAdmin) {
    await createUser({
      email: "admin@barcodephone.com",
      password: "admin123",
      name: "مدير النظام",
      role: "ADMIN"
    })
    console.log("Admin user created: admin@barcodephone.com / admin123")
  }
}
