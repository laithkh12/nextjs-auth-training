'use server'

import { createAuthSession, destroySession } from "@/lib/auth"
import { hashUserPassword, verifyPassword } from "@/lib/hash"
import { createUser, getUserByEmail } from "@/lib/user"
import { redirect } from "next/navigation"

export async function signup(prevState, formData) {
    const email = formData.get('email')
    const password = formData.get('password')

    // validate the data
    let errors = {}
    if (!email.includes('@')){
        errors.email = 'Please enter a valid email'
    }

    if (password.trim().length < 8){
        errors.password = 'Password must be at least 8 characters long'
    }

    if (Object.keys(errors).length > 0){
        return{
            errors,
        }
    }

    // store it in the db (create a new user)
    const hashedPassword = hashUserPassword(password)
    try {
        const id = createUser(email, hashedPassword)

        // create a new sesion
        await createAuthSession(id)

        redirect('/training')
    } catch (error) {
        if (error.code === 'SQLITE_CONSTRAINT_UNIQUE'){
            return {
                errors: {
                    email: 'The email is already exists'
                }
            }
        }
        throw error
    }    
}

export async function login(prevState, formData){
    const email = formData.get('email')
    const password = formData.get('password')

    // check if there is a valid user for this email and password
    const existingUser = getUserByEmail(email)
    if (!existingUser){
        return {
            errors: {
                email: "Could not authenticate user, please check your credentials"
            }
        }
    }

    // check if its a valid password
    const isValidPassword = verifyPassword(existingUser.password, password)
    if (!isValidPassword){
        return {
            errors: {
                password: "Could not authenticate user, please check your credentials"
            }
        }
    }

    // after the password and email where checked
    await createAuthSession(existingUser.id)
    redirect('/training')
}

export async function auth(mode, prevState, formData) {
    if (mode === 'login') {
        return login(prevState, formData)
    }
    return signup(prevState, formData)
}

export async function logout(){
    await destroySession()
    redirect('/')
}