const formidable = require('formidable')
const cloudinary = require('cloudinary').v2
const productModel = require('../../models/productModel');
const { responseReturn } = require('../../utiles/response');

class productController {
    add_product = async (req, res) => {
        const { id } = req;
        const form = new formidable.IncomingForm({ multiples: true })

        form.parse(req, async (err, field, files) => {
            let { name, category, description, stock, price, discount, shopName, brand, selectTag, selectColor } = field;
            const { images } = files;
            name = name[0].trim()
            const slug = name.split(' ').join('-')

            cloudinary.config({
                cloud_name: process.env.cloud_name,
                api_key: process.env.api_key,
                api_secret: process.env.api_secret,
                secure: true
            })

            const colorValues = JSON.parse(selectColor).map((item) => item.value)
            const tagValues = JSON.parse(selectTag).map((item) => item.label)

            try {
                let allImageUrl = [];

                for (let i = 0; i < images.length; i++) {
                    const result = await cloudinary.uploader.upload(images[i].filepath, { folder: 'product' })
                    allImageUrl = [...allImageUrl, result.secure_url]
                }
                let prod = await productModel.create({
                    sellerId: id,
                    name,
                    slug,
                    shopName: shopName[0],
                    category: category[0].trim(),
                    description: description[0].trim(),
                    stock: parseInt(stock[0]),
                    price: parseInt(price[0]),
                    discount: parseInt(discount[0]),
                    images: allImageUrl,
                    brand: brand[0].trim(),
                    colorArray: colorValues, tagArray: tagValues
                })
                res.status(201).json({ message: "Created successfully" });
            } catch (error) {
                console.log(error)
                responseReturn(req, 500, { error: error.message })
            }

        })
    }
    products_get = async (req, res) => {
        const { page, searchValue, parPage } = req.query
        const { id } = req;

        const skipPage = parseInt(parPage) * (parseInt(page) - 1);

        try {
            if (searchValue) {
                const products = await productModel.find({
                    $text: { $search: searchValue },
                    sellerId: id
                }).skip(skipPage).limit(parPage).sort({ createdAt: -1 })

                const totalProduct = await productModel.find({
                    $text: { $search: searchValue },
                    sellerId: id
                }).countDocuments()
                if (products.length === 0) {
                    responseReturn(res, 404, { message: "No products found matching the search criteria." });
                } else {
                    responseReturn(res, 200, { totalProduct, products });
                }
            } else {
                const products = await productModel.find({ sellerId: id }).skip(skipPage).limit(parPage).sort({ createdAt: -1 })
                const totalProduct = await productModel.find({ sellerId: id }).countDocuments()
                responseReturn(res, 200, { totalProduct, products })
            }
        } catch (error) {
            console.log(error.message)
        }
    }

    product_get = async (req, res) => {
        const { productId } = req.params;
        try {
            const product = await productModel.findById(productId)
            responseReturn(res, 200, { product })
        } catch (error) {
            console.log(error.message)
        }
    }
    discount_product_get = async (req, res) => {
        const { sellerId } = req.params;
        try {
            let product = await productModel.find({ sellerId: sellerId })
            product = product.filter((p) => p.discount > 0)

            responseReturn(res, 200, { product })
        } catch (error) {
            console.log(error.message)
        }
    }

    product_update = async (req, res) => {
        let { name, description, discount, price, brand, productId, stock, colors, tags } = req.body;
        name = name.trim()
        const slug = name.split(' ').join('-')
        const colorValues = colors.map(color => color.value);
        const tagValues = tags.map(tag => tag.label);
        try {
            await productModel.findByIdAndUpdate(productId, {
                name, description, discount, price, brand, productId, stock, slug, colorArray: colorValues, tagArray: tagValues
            })
            const product = await productModel.findById(productId)
            responseReturn(res, 200, { product, message: 'product update success' })
        } catch (error) {
            console.log(error.message)
            responseReturn(res, 500, { error: error.message })
        }
    }
    product_image_update = async (req, res) => {
        const form = new formidable.IncomingForm({ multiples: true })

        form.parse(req, async (err, field, files) => {
            const { productId, oldImage } = field;
            const { newImage } = files

            if (err) {
                responseReturn(res, 404, { error: err.message })
            } else {
                try {
                    cloudinary.config({
                        cloud_name: process.env.cloud_name,
                        api_key: process.env.api_key,
                        api_secret: process.env.api_secret,
                        secure: true
                    })
                    const result = await cloudinary.uploader.upload(newImage[0].filepath, { folder: 'product' })

                    if (result) {
                        let { images } = await productModel.findById(productId[0])
                        const index = images.findIndex(img => img === oldImage[0])
                        images[index] = result.url;

                        await productModel.findByIdAndUpdate(productId, {
                            images
                        })

                        const product = await productModel.findById(productId)
                        responseReturn(res, 200, { product, message: 'product image update success' })
                    } else {
                        responseReturn(res, 404, { error: 'image upload failed' })
                    }
                } catch (error) {
                    responseReturn(res, 404, { error: error.message })
                }
            }
        })
    }

    delete_product = async (req, res) => {
        const { productId } = req.params;

        try {
            const product = await productModel.findById(productId);

            cloudinary.config({
                cloud_name: process.env.cloud_name,
                api_key: process.env.api_key,
                api_secret: process.env.api_secret,
                secure: true
            })

            if (!product) {
                return res.status(404).json({ error: "Product not found." });
            }
            const images = product.images;
            for (let i = 0; i < images.length; i++) {
                const publicId = images[i].split("/").pop().split(".")[0];
                try {
                    const result = await cloudinary.uploader.destroy(publicId)
                } catch (error) {
                    console.error('Error deleting image:', error);
                }
            }
            // Delete the product from the database
            await productModel.findByIdAndDelete(productId);

            res.status(200).json({ message: "Product and associated images deleted successfully." });
        } catch (error) {
            console.error("Error deleting product:", error);
            res.status(500).json({ error: "Internal server error." });
        }
    }


}

module.exports = new productController()